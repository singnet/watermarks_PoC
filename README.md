# openwater-mk — Internal Demo

Licensed under the [Apache License 2.0](LICENSE).
See [SECURITY.md](SECURITY.md) for the threat model and known gaps.


Minimal runnable end-to-end demo of the OpenWater provenance watermark stack,
built on top of the `oprow` Version-0 reference SDK (vendored in-tree under
`./oprow/`; see [vendor/oprow_docs/VENDORING.md](vendor/oprow_docs/VENDORING.md)).

**Scope:** internal demo only. Image-only. Local Ed25519 keys.
Local/fake Arweave/IPFS manifest stores and a mock Cardano metadata anchor
provide the decentralized provenance shape without making network calls.
Three reference watermark carriers selectable via `--profile`:
`alpha_lsb` (lossless PNG only), `dct_qim` (default; JPEG-robust
locator), `dct_qim_robust` (5-coefficient spectral spread, same JPEG
profile as the reference on the demo corpus, structural template for
production tuning). Real Arweave/IPFS uploads, real Cardano transactions,
Rholang, and Hyperon land in V1+ per the OpenWater roadmap.

## What this shows

1. Sign a manifest binding artifact essence (PED-IMG-1) + creation claims
   with an Ed25519 key.
2. Embed the manifest locator into the artifact via the selected watermark carrier.
3. Persist watermarked PNG to disk.
4. Extract the locator from the watermarked image, resolve the manifest from
   a local content-addressed store, verify signature + essence binding +
   local trust policy.
5. Optionally persist the manifest through fake Arweave/IPFS-shaped stores
   and publish a mock Cardano metadata anchor.
6. Emit JSON verification and POC reports.

The security boundary, per the OpenWater design doc:

> Watermark/HDC layers are retrieval/routing aids. Final provenance requires
> manifest locator consistency, valid signatures, essence/content binding,
> and local trust policy.

The `--tamper` flag demonstrates this: a copy/paste or pixel-mutation attack
can leave the locator recoverable but **must** fail the essence check.

## Quick start

`openwater-mk` is glue over the upstream `oprow` Version-0 reference SDK,
which is **vendored in this repo** under `./oprow/`. No sibling checkout
needed. Source provenance for the vendored copy is documented in
[vendor/oprow_docs/VENDORING.md](vendor/oprow_docs/VENDORING.md).

Use Python 3.11-3.13 for local development. The pinned FastAPI/TestClient
test stack is not accepted on Python 3.14 until that combination is
verified separately.

For the full validation checklist and troubleshooting notes, see
[VALIDATION.md](VALIDATION.md).

### Run

```bash
./scripts/setup.sh          # create .venv, install demo (oprow vendored in-tree)
./scripts/demo.sh           # default dct_qim locator demo with synthetic image
./scripts/demo.sh --profile alpha_lsb  # full essence-verification path
.venv/bin/python -m openwater_mk.cli poc --out /tmp/openwater-poc
ls out/                     # watermarked.png, verify_report.json
```

Or by hand, via the installed CLI:

```bash
. .venv/bin/activate
openwater demo                                       # default profile (dct_qim)
openwater demo --profile alpha_lsb                   # full essence-verify path
openwater demo --profile alpha_lsb --tamper          # negative case: content_mismatch
openwater demo --profile alpha_lsb --transform png_rgba  # benign re-encode: verified
openwater demo --profile alpha_lsb --transform png_rgb   # alpha stripped: locator dies
openwater demo --profile alpha_lsb --transform jpeg_q82  # lossy: locator dies
openwater demo --profile dct_qim --transform jpeg_q60    # JPEG-robust: locator survives
openwater demo --profile dct_qim_robust --transform jpeg_cascade_85_70  # spectral spread
openwater poc --out /tmp/openwater-poc      # watermark + fake Arweave + mock Cardano POC
```

`openwater poc` is the Ben-task acceptance path: it signs and watermarks an
image, stores the manifest in a fake Arweave-shaped backend by default,
verifies the watermarked artifact, anchors the manifest commitment in the
mock Cardano ledger, verifies that anchor, and writes `poc_report.json`.

For a cross-process round-trip (sign-and-embed in one shot, verify later
against persisted artifacts):

```bash
openwater sign-embed --out /tmp/run1                          # local FileCAS
openwater sign-embed --storage fake-arweave --out /tmp/run2   # ar://<43-char txid>
openwater sign-embed --storage fake-ipfs    --out /tmp/run3   # ipfs://<CIDv1>
openwater inspect /tmp/run1/watermarked.png
openwater verify /tmp/run1/watermarked.png \
    --manifest-store /tmp/run1/manifests \
    --key /tmp/run1/key.json
# Verify can also walk multiple stores in order (e.g. IPFS cache then Arweave)
openwater verify /tmp/run2/watermarked.png \
    --manifest-store /tmp/run3/manifests \
    --manifest-store /tmp/run2/manifests \
    --key /tmp/run2/key.json
```

The `fake-arweave` and `fake-ipfs` backends emit realistic identifier
shapes (43-char base64url Arweave txid, base32 CIDv1) but do not make
network calls — they persist manifest bytes to a local fanout directory.
Real Arweave/IPFS adapters are stubbed in `openwater_mk/storage.py` and
are a localized swap-in once credentials are available.

`demo_internal.py` still works as a shim for the demo subcommand only.

## Layout

```
openwater-demo/
├── openwater_mk/           # installable orchestration package
│   ├── __init__.py         # public re-exports
│   ├── cli.py              # `openwater` console entrypoint
│   ├── pipeline.py         # run_demo, sign_and_embed, verify, anchor_*
│   ├── storage.py          # LocalFileStore / FakeArweaveStore / FakeIPFSStore
│   ├── cardano.py          # AnchorRecord, metadata-label 40961, MockCardanoBackend
│   ├── transforms.py       # named TRANSFORMS map for the CLI --transform flag
│   └── web/                # FastAPI service: server.py, jobs.py, templates.py
├── oprow/                  # vendored Version-0 SDK (see vendor/oprow_docs/)
├── tests/
│   ├── test_demo.py        # in-process pipeline
│   ├── test_cli.py         # CLI surface
│   ├── test_storage.py     # local/fake Arweave/fake IPFS stores
│   ├── test_cardano.py     # mock Cardano metadata anchor
│   ├── test_web.py         # FastAPI surface
│   └── oprow_upstream/     # vendored oprow test suite (85 cases)
├── vendor/oprow_docs/      # upstream README_STEP*.md + VENDORING.md
├── demo_internal.py        # legacy shim → `openwater demo`
├── scripts/
│   ├── setup.sh            # venv + install
│   └── demo.sh             # `openwater demo` wrapper
├── pyproject.toml          # package definition (ships openwater_mk + oprow)
├── out/                    # demo outputs (last run + committed samples)
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

## Watermark profiles and channel robustness

Three carriers are exposed via `--profile`. They share the same payload
codec, ECC framing, and pointer modes; only the per-block carrier
algorithm differs.

| Profile | Carrier | qim_delta | What it demonstrates |
| --- | --- | --- | --- |
| `alpha_lsb` | PNG alpha channel LSBs | n/a | Full essence-binding round-trip. The watermark does not touch luminance so PED-IMG-1 verifies. **Dies** the moment a channel strips alpha (JPEG, RGB re-save). |
| `dct_qim` (default) | One mid-frequency DCT coefficient `(3,2)` per 8x8 Y block | 64 | JPEG-robust locator survival. Locator round-trips PNG-RGB, JPEG q60+, and one-shot social cascades. **Essence binding fails by V0 design** — PED-IMG-1 is exact-hash and any luminance carrier perturbs Y. |
| `dct_qim_robust` | Five mid-frequency DCT coefficients per 8x8 block + majority vote | 64 | Spectral-spread template. On this corpus it tracks `dct_qim` exactly (JPEG noise is correlated across coefficients of the same block). It is shipped as the **structure** for V1 production tuning, not as a current robustness win. |

The CLI exit code reflects each profile's success criterion:

- `--profile alpha_lsb`: `rc=0` iff `verified=True` (full extraction +
  essence binding + signature + trust).
- `--profile dct_qim*`: `rc=0` iff `extraction_status=="extracted"` (the
  locator survived the channel). The verifier will still report
  `content_mismatch` because the embed perturbs luminance and PED-IMG-1
  is exact-hash; that's a documented V0 limitation, not a regression.

### Empirical matrix on the synthetic 192×192 corpus

Pinned by `tests/test_watermark_robust.py` with `FIXED_CREATED_AT` and
`FIXED_KEY` to keep the JPEG-knife-edge cells deterministic. ✓ =
`extracted`, ✗ = `no_watermark`. The `dct_qim*` rows never reach
`verified=True` for the V0 reason above; they're only measuring locator
survival.

| Transform | alpha_lsb | dct_qim | dct_qim_robust |
| --- | --- | --- | --- |
| (none) | ✓ verified | ✓ | ✓ |
| `png_rgba` | ✓ verified | ✓ | ✓ |
| `png_rgb` | ✗ | ✓ | ✓ |
| `jpeg_q82` | ✗ | ✓ | ✓ |
| `jpeg_q70` | ✗ | ✓ | ✓ |
| `jpeg_q60` | ✗ | ✓ | ✓ |
| `jpeg_cascade_85_70` | ✗ | ✓ | ✓ |
| `social_pipeline` | ✗ | ✗ | ✗ |
| `resize_0_9` | ✗ | ✗ | ✗ |

The bottom two rows fail because the V0 SDK has no synchronization
recovery — any resize / crop / rotation breaks the deterministic 8x8
block grid the QIM coefficients live on. Geometry-tolerant sync (cyclic
templates, autocorrelation peaks) is Tier 2.5 work and a V1 production
prerequisite.

Captured runs for every cell live under
`out/_transform_samples/<profile>/<transform>/` (watermarked PNG,
transformed image, JSON verify report).

### Security boundary stays unchanged

Recovering a locator is **not** proof of authenticity. The OpenWater
verifier requires manifest signature + essence binding + local trust
policy regardless of which carrier was used. The `--tamper` flag on the
`alpha_lsb` profile demonstrates this explicitly: the locator survives
the tamper, but `verification_status` becomes `content_mismatch` and the
demo returns rc=0 *because* it correctly rejected the tampered artifact.

## openwater.mk web service

A small FastAPI service exposes the pipeline over HTTP. No DB, no auth,
no rate limiting yet — V1 Slice B from the implementation-time-estimates
doc.

```bash
openwater serve --port 8000              # http://127.0.0.1:8000
# in another shell:
curl http://127.0.0.1:8000/healthz
JOB=$(curl -s -X POST -F storage=fake-arweave http://127.0.0.1:8000/sign-embed | jq -r .job_id)
curl -X POST http://127.0.0.1:8000/jobs/$JOB/verify
curl -X POST "http://127.0.0.1:8000/jobs/$JOB/anchor?epoch=0"
# Human-friendly HTML verify report:
xdg-open "http://127.0.0.1:8000/jobs/$JOB/report.html"
```

Interactive API docs at `/docs` (auto-generated). The service stores
per-job artifacts under `OPENWATER_JOBS_ROOT` (default
`/tmp/openwater-mk-jobs`).

### Hardening defaults

The service has **no authentication**, so it ships with these guardrails:

- `openwater serve --host 0.0.0.0` (or any non-loopback) refuses to start
  unless you pass `--unsafe-public`.
- Request bodies above `OPENWATER_MAX_UPLOAD_BYTES` (default 1 MB) get
  a `413`.
- `GET /jobs` returns `403` unless `OPENWATER_ADMIN_TOKEN` is set; the
  token is then required via either the `X-Admin-Token` header or
  `?token=`.
- `job_id` path parameters are validated against a strict 32-hex pattern.

See [SECURITY.md](SECURITY.md) for the full threat model and the list of
known gaps a real security audit should focus on.

## Cardano metadata anchoring (mock backend today)

Anchors are published per §16.6 of the design doc: a compact CBOR-friendly
commitment under metadata label ``40961`` (the experimental MVP label
specified in §16.6.3). The current backend is a process-local mock that
fakes Cardano-shaped tx hashes, slots, and block hashes — enough to drive
verification end-to-end and pin the metadata schema before any real
wallet is involved. ``BlockfrostCardanoBackend`` is stubbed for the real
path.

```bash
openwater sign-embed --storage fake-arweave --out /tmp/run-ar
openwater anchor /tmp/run-ar --out /tmp/run-ar-anchor --epoch 0
cat /tmp/run-ar-anchor/metadata.json          # the compact metadata as submitted
openwater verify-anchor /tmp/run-ar-anchor    # confirms tx, recomputes hashes, checks fields
```

## Defer to V1+

- Real Arweave uploads (need funded wallet + ``arweave-python-client``)
- Real IPFS pinning (need daemon or Pinata/web3.storage credentials)
- Real Cardano tx submission (need ``pycardano`` + funded wallet, e.g. via Blockfrost)
- SHORT64-HV pointer mode (for low-capacity channels)
- C2PA SDK / JUMBF packaging
- Rholang trust-machine contracts
- Hyperon/MeTTa policy evaluation
- Perceptual essence with tolerance threshold (PED-IMG-1 is exact-hash
  today; that's what blocks DCT-QIM from round-tripping `verified=True`)
- Synchronization-robust DCT/QIM watermark (current carriers die under
  resize, crop, rotation, social re-host)
