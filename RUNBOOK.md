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
