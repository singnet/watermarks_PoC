# openwater-mk — Internal Demo

Licensed under the [Apache License 2.0](LICENSE).
See [SECURITY.md](SECURITY.md) for the threat model and known gaps.


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

### Prerequisite: oprow sibling checkout

`openwater-mk` is glue over the upstream `oprow_step14_benchmarks` Version-0
reference SDK. That SDK has no PyPI release and is **not** vendored in this
repo, so you must place it as a sibling directory before running setup:

```
<parent>/
├── openwater-demo/             # this repo
└── oprow_step14_benchmarks/    # upstream Version-0 SDK (obtain separately)
```

`scripts/setup.sh` installs it editable via `pip install -e ../oprow_step14_benchmarks`.
Setup will fail with a missing-path error if the sibling directory is absent.

### Run

```bash
./scripts/setup.sh          # create .venv, install oprow + openwater-mk editable
./scripts/demo.sh           # run end-to-end demo with synthetic image
ls out/                     # watermarked.png, verify_report.json
```

Or by hand, via the installed CLI:

```bash
. .venv/bin/activate
openwater demo                          # in-process one-shot
openwater demo --tamper                 # negative case: content_mismatch
openwater demo --transform png_rgba     # benign re-encode: still verified
openwater demo --transform png_rgb      # alpha stripped: locator dies
openwater demo --transform jpeg_q82     # lossy: locator dies
```

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
├── openwater_mk/           # installable package
│   ├── __init__.py         # public re-exports
│   ├── cli.py              # `openwater` console entrypoint
│   ├── pipeline.py         # run_demo, sign_and_embed, verify, anchor_*
│   ├── storage.py          # LocalFileStore / FakeArweaveStore / FakeIPFSStore
│   ├── cardano.py          # AnchorRecord, metadata-label 40961, MockCardanoBackend
│   ├── transforms.py       # named TRANSFORMS map for the CLI --transform flag
│   └── web/                # FastAPI service: server.py, jobs.py, templates.py
├── tests/
│   ├── test_demo.py        # in-process pipeline (7 cases)
│   └── test_cli.py         # CLI surface (6 cases)
├── demo_internal.py        # legacy shim → `openwater demo`
├── scripts/
│   ├── setup.sh            # venv + install
│   └── demo.sh             # `openwater demo` wrapper
├── pyproject.toml          # openwater-mk package definition
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

## Channel robustness (alpha-LSB reference carrier only)

The reference watermark profile is alpha-LSB. It is deliberately fragile:
it shows the orchestration end-to-end but is **not** a production carrier.
`--transform` exercises three points on the channel-robustness spectrum:

| Transform | Expected extraction | Expected verification | Notes |
| --- | --- | --- | --- |
| `png_rgba` | `extracted` | `verified` | PNG re-encode preserving alpha: locator survives |
| `png_rgb` | `no_watermark` | `no_watermark` | PNG re-encode stripping alpha: carrier destroyed |
| `jpeg_q82` | `no_watermark` | `no_watermark` | Lossy JPEG: alpha gone, RGB also perturbed |

Captured runs under `out/_transform_samples/<name>/`. Production hostile-
channel watermarking is the V8 line item in the implementation-time-estimates
doc and is not on the V1 path.

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
- Robust DCT/QIM watermark (alpha-LSB survives PNG round-trip only — fails
  JPEG, social-media re-encode, screenshots)
