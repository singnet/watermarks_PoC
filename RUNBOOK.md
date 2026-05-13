# OpenWater Internal Demo — Runbook

Show in 5 commands. Total walkthrough ~3 minutes.

## Prereqs (one-time)

```bash
cd openwater-demo
./scripts/setup.sh
```

This creates `.venv/`, installs the demo (the oprow Version 0 SDK is
vendored in-tree under `./oprow/`), and runs the 85-case vendored upstream
test suite as a smoke check. Use Python 3.11-3.13; Python 3.14 is not part
of the supported test matrix yet.

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

### 3. Channel robustness — picking a profile

The CLI takes `--profile {alpha_lsb,dct_qim,dct_qim_robust}`. Defaults
to `dct_qim`. Quick guide:

| When | Profile | Why |
| --- | --- | --- |
| You want to demo the full essence-binding round-trip | `alpha_lsb` | The watermark lives in the alpha channel so PED-IMG-1 verifies exactly. |
| You want to demo locator survival under JPEG / social re-encode | `dct_qim` | Mid-frequency Y coefficient, well above the libjpeg quant grid at q60. |
| You want the structural template for V1 production carriers | `dct_qim_robust` | 5-coefficient spectral spread + majority vote. Same JPEG profile as `dct_qim` on the synthetic corpus; combine with spatial repetition + sync template for real-world robustness. |

```bash
./scripts/demo.sh --profile alpha_lsb --transform png_rgba   # -> verified
./scripts/demo.sh --profile alpha_lsb --transform png_rgb    # -> no_watermark
./scripts/demo.sh --profile alpha_lsb --transform jpeg_q82   # -> no_watermark
./scripts/demo.sh --profile dct_qim   --transform jpeg_q60   # -> extracted (content_mismatch)
./scripts/demo.sh --profile dct_qim   --transform jpeg_cascade_85_70  # -> extracted
./scripts/demo.sh --profile dct_qim_robust --transform jpeg_q60      # -> extracted
```

Two talking points to lead with:

1. **alpha-LSB is fragile by design.** It's the reference carrier; real
   social channels recompress to JPEG and strip alpha. The dct_qim
   profile is what survives that.
2. **DCT-QIM verifies `content_mismatch`, not `verified`.** That's
   expected V0 behaviour: PED-IMG-1 is exact-hash and any luminance
   carrier perturbs Y. The CLI's success criterion for DCT-QIM is
   *locator extraction*, not full essence verification. A perceptual
   essence with tolerance is V1+ work, captured in the README's
   "Defer to V1+" list.

See `out/_transform_samples/<profile>/<transform>/` for committed runs
of every (profile × transform) cell.

### 4. Tests as living acceptance criteria

```bash
.venv/bin/python -m pytest tests/test_demo.py tests/test_cli.py tests/test_storage.py tests/test_cardano.py tests/test_watermark_robust.py -v
.venv/bin/python -m pytest tests/test_web.py -v
.venv/bin/python -m pytest tests/oprow_upstream -v
```

The first command is the core local acceptance suite; on this branch it
should show the CLI, storage, Cardano, and watermark robustness tests
passing. The web suite exercises FastAPI via
`TestClient` and requires the supported Python/dependency range from
`pyproject.toml`. The upstream suite verifies the vendored OProW reference
SDK behavior.

### 4b. Cross-process workflow (closer to the V1 shape)

```bash
openwater sign-embed --out /tmp/run1
openwater inspect /tmp/run1/watermarked.png      # locator only, no verify
openwater verify /tmp/run1/watermarked.png \
    --manifest-store /tmp/run1/manifests \
    --key /tmp/run1/key.json
```

Talking point: this is the shape the real product will use. The
trust-policy and key-resolver pieces will move from a local JSON envelope
to a registry-backed lookup. The CLI surface stays the same.

### 4e. openwater.mk hosted service (local FastAPI)

```bash
openwater serve --port 8000 &
sleep 1
JOB=$(curl -s -X POST -F storage=fake-arweave http://127.0.0.1:8000/sign-embed | jq -r .job_id)
echo "job_id=$JOB"
curl -s http://127.0.0.1:8000/jobs/$JOB | jq .
curl -s -X POST http://127.0.0.1:8000/jobs/$JOB/verify | jq .
curl -s -X POST "http://127.0.0.1:8000/jobs/$JOB/anchor?epoch=0" | jq .
echo "open http://127.0.0.1:8000/jobs/$JOB/report.html"
kill %1
```

Talking point: this is the openwater.mk hosted verifier surface. The
exposed endpoints map 1-to-1 onto the CLI subcommands so anything that
works locally also works over HTTP. The HTML verify report
(`/jobs/{id}/report.html`) is the version of the page a non-technical
user would see — it includes the security caveat from the design doc
about provenance vs. authenticity.

### 4d. Cardano metadata anchor (mock backend)

```bash
openwater sign-embed --storage fake-arweave --out /tmp/run-ar
openwater anchor /tmp/run-ar --out /tmp/run-ar-anchor --epoch 0
cat /tmp/run-ar-anchor/metadata.json
openwater verify-anchor /tmp/run-ar-anchor
```

Expected: `verify-anchor` prints `anchor_ok=True  confirmations=1`.

Talking points:

- Metadata label `40961` is the experimental MVP label called out in
  §16.6.3 of the design doc. Schema is the §16.6.4 compact CBOR map:
  `{v, p, t, sid, e, rh, ah, refs?, ok}`. Field meanings: schema
  version, profile string, record type, subject id (manifest key),
  epoch, root hash, anchor-record hash (committed on-chain), off-chain
  refs to Arweave/IPFS, and a 16-byte digest of the operator key id.
- Payload typically lands at ~200-300 bytes of CBOR for a single anchor.
  Cardano metadata strings are capped at 64 bytes individually but the
  total payload can be many KB. We stay well under that.
- The mock backend persists a JSON "ledger" file. Each `openwater anchor`
  call appends a fake tx with random `tx_hash` / `block_hash` and a
  monotonically-increasing `slot`. `verify-anchor` re-derives the
  anchor record hash, fetches the tx from the ledger, and asserts
  every metadata field matches.
- Real backend swap is one class:
  `BlockfrostCardanoBackend` is wired with the exact `requests` /
  `pycardano` calls in `openwater_mk/cardano.py`. It raises
  `NotImplementedError` today because it needs a funded wallet.

### 4c. Pluggable storage backends — Arweave and IPFS shapes today

```bash
openwater sign-embed --storage fake-arweave --out /tmp/run-ar
cat /tmp/run-ar/storage_uri.txt        # ar://<43-char base64url txid>

openwater sign-embed --storage fake-ipfs --out /tmp/run-ipfs
cat /tmp/run-ipfs/storage_uri.txt      # ipfs://<base32 CIDv1>
```

Talking point: the `fake-*` backends emit the right identifier shapes
without making any network calls — they persist manifest bytes to a local
fanout directory keyed by a deterministic hash. Real Arweave / IPFS
adapters (`ArweaveGatewayStore`, `IPFSDaemonStore`) are stubbed in
`openwater_mk/storage.py` with the exact wiring needed once a funded
wallet (Arweave) or a daemon / Pinata / web3.storage credentials (IPFS)
are available. The pipeline does not care which backend it is talking to.

Demo `verify` against multiple stores in order (an IPFS cache then
Arweave durable storage, for example):

```bash
openwater verify /tmp/run-ar/watermarked.png \
    --manifest-store /tmp/run-ipfs/manifests \
    --manifest-store /tmp/run-ar/manifests \
    --key /tmp/run-ar/key.json
```

### 5. Cleanup (optional)

```bash
rm -rf out/watermarked.png out/verify_report.json out/transformed_*
# Keep out/_tamper_sample/ and out/_transform_samples/ — they are committed.
```

## Where things live

| Thing | Path |
| --- | --- |
| Orchestration | `demo_internal.py` (`run_demo()` is the entry function) |
| Tests | `tests/test_demo.py`, `tests/test_cli.py`, `tests/test_storage.py`, `tests/test_cardano.py`, `tests/test_web.py` |
| Upstream oprow SDK | `./oprow/` (vendored; see `vendor/oprow_docs/VENDORING.md`) |
| Sample outputs | `out/_tamper_sample/`, `out/_transform_samples/<name>/` |
| Design doc | `../OpenWater_Comprehensive_Design.pdf` (74 pages) |
| Effort estimates | `../OpenWater_Implementation_Time_Estimates_v0_1.pdf` |
| Source code, oprow | in-tree `oprow/`, treated as Version 0 reference scaffold |

## Honest caveats to flag verbally

1. **Reference-grade watermarks.** Three carriers ship today; none are
   production-grade. `alpha_lsb` dies on JPEG. `dct_qim` survives JPEG
   but cannot round-trip PED-IMG-1 essence in V0 because the essence is
   exact-hash and the carrier perturbs Y. `dct_qim_robust` is a
   structural template, not a current robustness win.
2. **No real chain anchor yet.** The demo has local fake Arweave/IPFS
   stores and a mock Cardano ledger. Real uploads and transactions are
   still future integration work.
3. **Local trust policy only.** No transparency log, no trust bundle from
   a registry, no key transparency. The verifier accepts the local
   ephemeral key as trusted for demo purposes only.
4. **Provenance not authenticity.** A `verified=true` result means "this
   artifact's essence binds to a signed manifest from a trusted key". It
   does **not** mean "the events depicted are true" — the OpenWater UX
   layer is responsible for making that distinction visible.
